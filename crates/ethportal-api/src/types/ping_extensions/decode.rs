use anyhow::{anyhow, bail};
use ssz::Decode;

use super::{
    extension_types::Extensions,
    extensions::{
        type_0::ClientInfoRadiusCapabilities, type_1::BasicRadius, type_2::HistoryRadius,
        type_65535::PingError,
    },
};
use crate::types::portal_wire::CustomPayload;

#[derive(Debug, Clone)]
pub enum DecodedExtension {
    Capabilities(ClientInfoRadiusCapabilities),
    BasicRadius(BasicRadius),
    HistoryRadius(HistoryRadius),
    Error(PingError),
}

impl From<DecodedExtension> for Extensions {
    fn from(value: DecodedExtension) -> Self {
        match value {
            DecodedExtension::Capabilities(_) => Extensions::Capabilities,
            DecodedExtension::BasicRadius(_) => Extensions::BasicRadius,
            DecodedExtension::HistoryRadius(_) => Extensions::HistoryRadius,
            DecodedExtension::Error(_) => Extensions::Error,
        }
    }
}

impl DecodedExtension {
    pub fn decode_extension(payload_type: u16, payload: CustomPayload) -> anyhow::Result<Self> {
        let Ok(extension_type) = Extensions::try_from(payload_type) else {
            bail!("Failed to decode extension type {payload_type}");
        };

        match extension_type {
            Extensions::Capabilities => {
                let capabilities = ClientInfoRadiusCapabilities::from_ssz_bytes(&payload.payload)
                    .map_err(|err| {
                    anyhow!("Failed to decode ClientInfoRadiusCapabilities: {err:?}")
                })?;
                Ok(DecodedExtension::Capabilities(capabilities))
            }
            Extensions::BasicRadius => {
                let basic_radius = BasicRadius::from_ssz_bytes(&payload.payload)
                    .map_err(|err| anyhow!("Failed to decode BasicRadius: {err:?}"))?;
                Ok(DecodedExtension::BasicRadius(basic_radius))
            }
            Extensions::HistoryRadius => {
                let history_radius = HistoryRadius::from_ssz_bytes(&payload.payload)
                    .map_err(|err| anyhow!("Failed to decode HistoryRadius: {err:?}"))?;
                Ok(DecodedExtension::HistoryRadius(history_radius))
            }
            Extensions::Error => {
                let error = PingError::from_ssz_bytes(&payload.payload)
                    .map_err(|err| anyhow!("Failed to decode PingError: {err:?}"))?;
                Ok(DecodedExtension::Error(error))
            }
        }
    }
}
