use std::net::Ipv4Addr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_server::authority::{Authority, LookupError, LookupOptions, LookupRecords, MessageRequest, ZoneType};
use hickory_server::server::RequestInfo;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{LowerName, Name, RData, RecordSet, RecordType};

use crate::AppState;

pub struct SeederAuthority {
    origin: LowerName,
    state: Arc<AppState>,
}

impl SeederAuthority {
    pub fn new(origin: LowerName, state: Arc<AppState>) -> Self {
        Self { origin, state }
    }

    fn build_lookup(&self, name: &LowerName, lookup_options: LookupOptions) -> Result<LookupRecords, LookupError> {
        let nodes = self.state.good_nodes.lock().unwrap();
        let mut rdatas = Vec::new();
        for node in nodes.iter() {
            if let Ok(ip) = node.ip_address.parse::<Ipv4Addr>() {
                rdatas.push(RData::A(A(ip)));
            }
        }
        if rdatas.is_empty() {
            return Err(LookupError::from(hickory_proto::op::ResponseCode::NXDomain));
        }
        let name: Name = name.clone().into();
        let mut record_set = RecordSet::new(&name, RecordType::A, 60);
        for rdata in rdatas {
            record_set.add_rdata(rdata);
        }
        Ok(LookupRecords::new(lookup_options, Arc::new(record_set)))
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
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        if rtype != RecordType::A {
            return Err(LookupError::from(hickory_proto::op::ResponseCode::NoError));
        }
        self.build_lookup(name, lookup_options)
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
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Ok(LookupRecords::new(lookup_options, Arc::new(RecordSet::new(&hickory_proto::rr::Name::root(), RecordType::A, 0))))
    }
}
