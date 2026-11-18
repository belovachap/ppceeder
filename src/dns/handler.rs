use std::net::Ipv4Addr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_dns::authority::{Authority, Lookup, LookupOptions, ZoneType};
use hickory_dns::proto::op::{Message, ResponseCode};
use hickory_dns::proto::rr::rdata::A;
use hickory_dns::proto::rr::{Name, RData, Record, RecordType};

use crate::AppState;

pub struct SeederAuthority {
    origin: Name,
    state: Arc<AppState>,
}

impl SeederAuthority {
    pub fn new(origin: Name, state: Arc<AppState>) -> Self {
        Self { origin, state }
    }

    fn build_lookup(&self, name: &Name) -> Result<Lookup, ResponseCode> {
        let nodes = self.state.good_nodes.lock().unwrap();
        let mut records = Vec::new();
        for node in nodes.iter() {
            if let Ok(ip) = node.ip_address.parse::<Ipv4Addr>() {
                let mut record = Record::new();
                record.set_name(name.clone());
                record.set_rrtype(RecordType::A);
                record.set_ttl(60);
                record.set_data(RData::A(A(ip)));
                records.push(record);
            }
        }
        if records.is_empty() {
            return Err(ResponseCode::NXDomain);
        }
        Ok(Lookup::new(records))
    }
}

#[async_trait]
impl Authority for SeederAuthority {
    fn origin(&self) -> &Name {
        &self.origin
    }

    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &Message) -> Result<bool, ResponseCode> {
        Err(ResponseCode::NotImp)
    }

    async fn lookup(
        &self,
        name: &Name,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> Result<Lookup, ResponseCode> {
        if rtype != RecordType::A {
            return Err(ResponseCode::NoError);
        }
        self.build_lookup(name)
    }

    async fn search(
        &self,
        name: &Name,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Lookup, ResponseCode> {
        self.lookup(name, rtype, lookup_options).await
    }

    async fn query(
        &self,
        request: &Message,
        lookup_options: LookupOptions,
    ) -> Result<Lookup, ResponseCode> {
        let name = request.queries().first().map(|q| q.name().clone());
        let rtype = request.queries().first().map(|q| q.query_type());
        match (name, rtype) {
            (Some(name), Some(rtype)) => self.lookup(&name, rtype, lookup_options).await,
            _ => Err(ResponseCode::FormErr),
        }
    }
}
