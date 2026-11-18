use std::net::Ipv4Addr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_server::authority::{Authority, LookupError, LookupOptions, LookupRecords, MessageRequest, ZoneType};
use hickory_server::server::RequestInfo;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{LowerName, RData, Record, RecordType};

use crate::AppState;

pub struct SeederAuthority {
    origin: LowerName,
    state: Arc<AppState>,
}

impl SeederAuthority {
    pub fn new(origin: LowerName, state: Arc<AppState>) -> Self {
        Self { origin, state }
    }

    fn build_lookup(&self, name: &LowerName) -> Result<LookupRecords, LookupError> {
        let nodes = self.state.good_nodes.lock().unwrap();
        let mut records = Vec::new();
        for node in nodes.iter() {
            if let Ok(ip) = node.ip_address.parse::<Ipv4Addr>() {
                let mut record = Record::new();
                record.set_name(name.clone().into());
                record.set_rr_type(RecordType::A);
                record.set_ttl(60);
                record.set_data(Some(RData::A(A(ip))));
                records.push(record);
            }
        }
        if records.is_empty() {
            return Err(LookupError::from(hickory_proto::op::ResponseCode::NXDomain));
        }
        Ok(LookupRecords::new(records))
    }
}

#[async_trait]
impl Authority for SeederAuthority {
    type Lookup = LookupRecords;

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> Result<bool, hickory_proto::op::ResponseCode> {
        Err(hickory_proto::op::ResponseCode::NotImp)
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        if rtype != RecordType::A {
            return Err(LookupError::from(hickory_proto::op::ResponseCode::NoError));
        }
        self.build_lookup(name)
    }

    async fn search(
        &self,
        request: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.lookup(request.query.name(), request.query.query_type(), lookup_options).await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Ok(LookupRecords::new(Vec::new()))
    }
}
