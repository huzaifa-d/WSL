// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(feature = "translator")]

use serde_json::{Value, json};
use wslc_aci_bridge::translate::translate;

fn translate_json(input: Value) -> Value {
    serde_json::to_value(translate(&input.to_string()).unwrap()).unwrap()
}

fn request() -> Value {
    json!({
        "version": "1.1.0-alpha",
        "containment": "microvm",
        "microvm": {"image": "example.com/repo:tag"},
        "process": {"commandLine": "printf OK"}
    })
}

#[test]
fn translates_image_memory_and_deny_network() {
    let mut input = request();
    input["microvm"]["provision"] = json!({"memoryMib": 256});
    input["network"] = json!({"egress": {"default": "deny"}});
    input["process"]["timeout"] = json!(30000);

    let run = translate_json(input);
    assert_eq!(
        run["provision"]["spec"]["image"]["reference"],
        "example.com/repo:tag"
    );
    assert_eq!(run["provision"]["spec"]["resources"]["memoryMib"], 256);
    assert_eq!(
        run["provision"]["request"]["network"]["egress"]["default"],
        "deny"
    );
    assert_eq!(
        run["provision"]["request"]["network"]["ingress"]["default"],
        "deny"
    );
    assert_eq!(
        run["provision"]["request"]["network"]["ingress"]["hostLoopback"],
        "deny"
    );
    assert_eq!(run["exec"]["process"]["commandLine"], "printf OK");
    assert_eq!(run["exec"]["process"]["timeout"], 30000);
}

#[test]
fn preserves_filesystem_network_proxy_and_process_fields() {
    let mut input = request();
    input["filesystem"] = json!({
        "readonlyPaths": ["C:\\readonly"],
        "readwritePaths": ["C:\\readwrite"],
        "deniedPaths": ["C:\\readonly\\denied"]
    });
    input["network"] = json!({
        "egress": {
            "default": "deny",
            "allow": [{
                "to": [{"cidr": "192.0.2.0/24", "except": ["192.0.2.128/25"]}],
                "ports": [{"protocol": "tcp", "port": 80, "endPort": 81}]
            }],
            "deny": [{"ports": [{"protocol": "udp", "port": 53}]}]
        },
        "ingress": {"default": "deny", "hostLoopback": "allow"}
    });
    input["runtimeConfig"] = json!({"networkProxy": "http://127.0.0.1:8080"});
    input["process"] = json!({
        "commandLine": "printf OK",
        "cwd": "/work",
        "env": ["K=V"],
        "inheritDefaultEnv": true,
        "timeout": 12
    });

    let run = translate_json(input);
    let provision = &run["provision"]["request"];
    assert_eq!(
        provision["filesystem"]["readonlyPaths"],
        json!(["C:\\readonly"])
    );
    assert_eq!(
        provision["filesystem"]["readwritePaths"],
        json!(["C:\\readwrite"])
    );
    assert_eq!(
        provision["filesystem"]["deniedPaths"],
        json!(["C:\\readonly\\denied"])
    );
    assert_eq!(
        provision["network"]["egress"]["allow"][0]["to"][0]["cidr"],
        "192.0.2.0/24"
    );
    assert_eq!(
        provision["network"]["egress"]["allow"][0]["to"][0]["except"],
        json!(["192.0.2.128/25"])
    );
    assert_eq!(
        provision["network"]["egress"]["allow"][0]["ports"][0],
        json!({"protocol": "tcp", "port": 80, "endPort": 81})
    );
    assert_eq!(
        provision["network"]["egress"]["deny"][0]["ports"][0],
        json!({"protocol": "udp", "port": 53})
    );
    assert_eq!(provision["network"]["ingress"]["hostLoopback"], "allow");
    assert_eq!(
        provision["runtimeConfig"]["networkProxy"],
        "http://127.0.0.1:8080"
    );
    assert_eq!(
        run["exec"]["process"],
        json!({
            "commandLine": "printf OK", "cwd": "/work", "env": ["K=V"],
            "inheritDefaultEnv": true, "timeout": 12
        })
    );
}

#[test]
fn preserves_absent_network_and_absent_versus_empty_environment() {
    let input = request();
    let absent = translate_json(input.clone());
    assert!(absent["provision"]["request"].get("network").is_none());
    assert!(absent["exec"]["process"].get("env").is_none());

    let mut empty = input;
    empty["network"] = json!({});
    empty["process"]["env"] = json!([]);
    let translated = translate_json(empty);
    assert_eq!(
        translated["provision"]["request"]["network"]["egress"]["default"],
        "deny"
    );
    assert_eq!(translated["exec"]["process"]["env"], json!([]));
}

#[test]
fn accepts_metadata_and_ignored_fallback() {
    let mut input = request();
    input["$schema"] = json!("https://example.com/schema");
    input["_comment"] = json!("example");
    input["fallback"] = json!({"allowDaclMutation": true});
    assert!(translate(&input.to_string()).is_ok());
}

#[test]
fn rejects_unrepresentable_policies_and_other_backends() {
    for (field, value) in [
        ("ui", json!({"disable": true})),
        ("lifecycle", json!({"destroyOnExit": false})),
        ("lifecycle", json!({"preservePolicy": true})),
        ("containerId", json!("requested-id")),
        ("unknown", json!(true)),
    ] {
        let mut input = request();
        input[field] = value;
        assert!(translate(&input.to_string()).is_err(), "accepted {field}");
    }

    let mut input = request();
    input["containment"] = json!("process");
    input.as_object_mut().unwrap().remove("microvm");
    assert!(translate(&input.to_string()).is_err());
    assert!(translate(r#"{"version":"1.1.0-alpha","phase":"start"}"#).is_err());
}

#[test]
fn preserves_default_protocols_and_rule_order() {
    let mut input = request();
    input["network"] = json!({
        "egress": {
            "default": "allow",
            "allow": [{"to": [{"cidr": "2001:db8::/32"}]}],
            "deny": [
                {"ports": [{"port": 443}]},
                {"ports": [{"protocol": "icmp"}]}
            ]
        },
        "ingress": {"default": "allow", "hostLoopback": "deny"}
    });
    let translated = translate_json(input);
    let network = &translated["provision"]["request"]["network"];
    assert_eq!(network["egress"]["default"], "allow");
    assert_eq!(
        network["egress"]["allow"][0]["to"][0]["cidr"],
        "2001:db8::/32"
    );
    assert_eq!(network["egress"]["deny"][0]["ports"][0]["protocol"], "any");
    assert_eq!(network["egress"]["deny"][0]["ports"][0]["port"], 443);
    assert_eq!(network["egress"]["deny"][1]["ports"][0]["protocol"], "icmp");
    assert_eq!(network["ingress"]["default"], "allow");
    assert_eq!(network["ingress"]["hostLoopback"], "deny");
}

#[test]
fn passes_explicit_environment_and_timeout_to_aci() {
    let mut input = request();
    input["process"]["env"] = json!([]);
    input["process"]["inheritDefaultEnv"] = json!(false);
    input["process"]["timeout"] = json!(0);
    let translated = translate_json(input);
    assert_eq!(translated["exec"]["process"]["env"], json!([]));
    assert_eq!(translated["exec"]["process"]["inheritDefaultEnv"], false);
    assert_eq!(translated["exec"]["process"]["timeout"], 0);
}

#[test]
fn rejects_unknown_fields_and_null_instead_of_dropping_them() {
    let mut unknown = request();
    unknown["network"] = json!({"egress": {"default": "deny", "futurePolicy": true}});
    assert!(translate(&unknown.to_string()).is_err());

    let mut null = request();
    null["process"]["env"] = Value::Null;
    assert!(translate(&null.to_string()).is_err());
}
