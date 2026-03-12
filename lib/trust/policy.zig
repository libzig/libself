pub const Mode = enum {
    accept_any,
    tofu,
    pinned,
};

pub const Decision = enum {
    accepted,
    accepted_and_pinned,
    rejected,
};
