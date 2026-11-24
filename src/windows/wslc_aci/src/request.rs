// Copyright (C) Microsoft Corporation. All rights reserved.

use aci_edge_sandboxes_model::{ExecRequest, wire::ProvisionInput};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AciOneShot {
    pub provision: ProvisionInput,
    pub exec: ExecRequest,
}
