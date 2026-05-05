%% Envelope record — carries the tainted cmd field.
-record(envelope, {
    kind   = run,
    cmd    = "",
    user   = "anon",
    length = 0,
    extras = []
}).
