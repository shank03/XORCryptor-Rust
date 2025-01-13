use std::{
    error::Error,
    fmt::{Debug, Display},
};

pub enum XRCError {
    InvalidKeyLength,
    EmptyInput,
}
impl XRCError {
    fn as_str(&self) -> &str {
        match self {
            XRCError::InvalidKeyLength => "Key length must be at least 6",
            XRCError::EmptyInput => "Given input vec is empty",
        }
    }
}

impl Debug for XRCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl Display for XRCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Error for XRCError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

pub type XRCResult<T> = Result<T, XRCError>;
