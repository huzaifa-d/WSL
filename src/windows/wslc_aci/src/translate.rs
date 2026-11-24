// Copyright (C) Microsoft Corporation. All rights reserved.
// Policy field mapping is based on microsoft/mxc at 40eebd39ab5e5a02d350169a8c96c28b33ddba7e (MIT).

use aci_edge_sandboxes_model::{
    Access, EgressPolicy, ExecRequest, FilesystemPolicy, ImageSource, IngressPolicy, NetworkPeer,
    NetworkPolicy, NetworkPort, NetworkRule, Protocol, ProvisionRequest, RuntimeConfig,
    SandboxSpec, wire::ProvisionInput,
};
use mxc_sdk::mxc_contract::dev::{
    self, Network, NetworkAction, NetworkEgress, NetworkIngress, NetworkProtocol,
    OneShotContainment, OneShotRequest, OptionalField, Request,
};
use std::path::PathBuf;
use std::time::Duration;

pub use crate::request::AciOneShot;

fn access(value: Option<NetworkAction>) -> Access {
    match value {
        Some(NetworkAction::Allow) => Access::Allow,
        Some(NetworkAction::Deny) | None => Access::Deny,
    }
}

fn protocol(value: Option<NetworkProtocol>) -> Protocol {
    match value {
        Some(NetworkProtocol::Tcp) => Protocol::Tcp,
        Some(NetworkProtocol::Udp) => Protocol::Udp,
        Some(NetworkProtocol::Icmp) => Protocol::Icmp,
        Some(NetworkProtocol::Any) | None => Protocol::Any,
    }
}

fn rules(value: OptionalField<Vec<dev::NetworkRule>>) -> Vec<NetworkRule> {
    value
        .into_option()
        .unwrap_or_default()
        .into_iter()
        .map(|rule| NetworkRule {
            to: rule
                .to
                .into_option()
                .map(dev::NonEmptyVec::into_inner)
                .unwrap_or_default()
                .into_iter()
                .map(|peer| NetworkPeer {
                    cidr: peer.cidr,
                    except: peer.except.into_option().unwrap_or_default(),
                })
                .collect(),
            ports: rule
                .ports
                .into_option()
                .map(dev::NonEmptyVec::into_inner)
                .unwrap_or_default()
                .into_iter()
                .map(|port| NetworkPort {
                    protocol: protocol(port.protocol.into_option()),
                    port: port.port.into_option().map(std::num::NonZeroU16::get),
                    end_port: port.end_port.into_option().map(std::num::NonZeroU16::get),
                })
                .collect(),
        })
        .collect()
}

fn network(value: Network) -> NetworkPolicy {
    let Network { egress, ingress } = value;
    let egress = match egress.into_option() {
        Some(NetworkEgress {
            default,
            allow,
            deny,
        }) => EgressPolicy {
            default: access(default.into_option()),
            allow: rules(allow),
            deny: rules(deny),
        },
        None => EgressPolicy::new(Access::Deny),
    };
    let ingress = match ingress.into_option() {
        Some(NetworkIngress {
            default,
            host_loopback,
        }) => IngressPolicy {
            default: access(default.into_option()),
            host_loopback: Some(access(host_loopback.into_option())),
        },
        None => IngressPolicy {
            default: Access::Deny,
            host_loopback: Some(Access::Deny),
        },
    };
    NetworkPolicy { egress, ingress }
}

pub fn translate(json: &str) -> Result<AciOneShot, String> {
    let request = match dev::parse_request(json).map_err(|error| error.to_string())? {
        Request::OneShot(request) => *request,
        _ => return Err("only one-shot requests are supported".into()),
    };
    let OneShotRequest {
        schema: _,
        comment: _,
        version: _,
        container_id,
        containment,
        lifecycle,
        process,
        filesystem,
        fallback: _,
        network: network_input,
        ui,
        process_container,
        lxc,
        seatbelt,
        runtime_config,
        telemetry,
        test,
        windows_sandbox,
        wslc,
        hyperlight,
        microvm,
    } = request;

    if !matches!(containment.into_option(), Some(OneShotContainment::Microvm)) {
        return Err("only MicroVM containment is supported".into());
    }
    if container_id.as_ref().is_some()
        || ui.as_ref().is_some()
        || process_container.as_ref().is_some()
        || lxc.as_ref().is_some()
        || seatbelt.as_ref().is_some()
        || telemetry.as_ref().is_some()
        || test.as_ref().is_some()
        || windows_sandbox.as_ref().is_some()
        || wslc.as_ref().is_some()
        || hyperlight.as_ref().is_some()
    {
        return Err("the request contains a field that ACI cannot represent".into());
    }
    if let Some(lifecycle) = lifecycle.into_option()
        && (lifecycle.destroy_on_exit.into_option() == Some(false)
            || lifecycle.preserve_policy.into_option() == Some(true))
    {
        return Err("the requested lifecycle cannot be represented by a one-shot run".into());
    }

    let microvm = microvm.into_option().ok_or("microvm.image is required")?;
    let mut spec =
        SandboxSpec::new().with_image(ImageSource::Reference(microvm.image.into_inner()));
    if let Some(memory) = microvm
        .provision
        .into_option()
        .and_then(|provision| provision.memory_mib.into_option())
    {
        spec = spec.with_memory_mib(memory);
    }

    let filesystem = filesystem.into_option().map(|filesystem| FilesystemPolicy {
        readonly_paths: filesystem
            .readonly_paths
            .into_option()
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        readwrite_paths: filesystem
            .readwrite_paths
            .into_option()
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        denied_paths: filesystem
            .denied_paths
            .into_option()
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect(),
    });
    let runtime_config = runtime_config.into_option().and_then(|runtime| {
        runtime
            .network_proxy
            .into_option()
            .map(|network_proxy| RuntimeConfig {
                network_proxy: Some(network_proxy),
            })
    });
    let provision = ProvisionInput {
        request: ProvisionRequest {
            filesystem,
            network: network_input.into_option().map(network),
            runtime_config,
            ..Default::default()
        },
        spec,
    };

    let mut exec = ExecRequest::command_line(process.command_line.into_inner());
    exec.process.cwd = process.cwd.into_option();
    exec.process.env = process.env.into_option();
    exec.process.inherit_default_env = process.inherit_default_env.into_option();
    exec.process.timeout = process
        .timeout
        .into_option()
        .map(|millis| Duration::from_millis(u64::from(millis)));

    Ok(AciOneShot { provision, exec })
}
