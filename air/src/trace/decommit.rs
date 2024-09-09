use swiftness_commitment::table;

use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;
#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
#[derive(Error, Debug)]
pub enum Error<F: SimpleField + PoseidonHash> {
    #[error("Table Error")]
    Table(#[from] table::decommit::Error<F>),
}

#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;

#[derive(Error, Debug)]
#[cfg(not(feature = "std"))]
pub enum Error<F: SimpleField> {
    #[error("Table Error")]
    Table(#[from] table::decommit::Error<F>),
}
