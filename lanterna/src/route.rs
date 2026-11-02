//! The closed set of ClickHouse HTTP routes lanterna can speak, and the one
//! place their paths are rendered.
//!
//! The HTTP interface has one door: `POST /` with the statement in the body.
//! That door is the whole write surface of the server, so lanterna never
//! lets a caller hold it: [`Route`] has exactly one arm, [`Route::Query`],
//! and the only body that ever reaches it is the text rendered from a
//! closed [`crate::sql::Question`]. There is no arm for an insert, a DDL
//! statement, a mutation or a settings change. A call that would change
//! ClickHouse state is not refused at runtime; it is `E0599`, because no
//! such arm exists.
//!
//! ```compile_fail,E0599
//! let _ = lanterna::Route::Insert;
//! ```
//!
//! ```compile_fail,E0599
//! let _ = lanterna::transport::Method::Delete;
//! ```

use std::fmt;

/// The HTTP verb a route is spoken with. Derived from the route, never
/// chosen by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// The statement travels in the body.
    Post,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Post => f.write_str("POST"),
        }
    }
}

/// Every HTTP route lanterna can put a request to. Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Route {
    /// `POST /` — run one rendered, read-only statement.
    Query,
}

impl Route {
    /// The verb this route is spoken with.
    #[must_use]
    pub const fn method(&self) -> Method {
        match self {
            Self::Query => Method::Post,
        }
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query => f.write_str("/"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_only_route_is_a_post_to_the_root() {
        assert_eq!(Route::Query.method(), Method::Post);
        assert_eq!(Route::Query.to_string(), "/");
        assert_eq!(Method::Post.to_string(), "POST");
    }

    #[test]
    fn matching_every_route_without_a_wildcard_pins_the_closed_set() {
        let route = Route::Query;
        let seen = match route {
            Route::Query => "query",
        };
        assert_eq!(seen, "query");
    }
}
