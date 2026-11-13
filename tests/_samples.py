"""A value matching each registry path-param pattern. A new pattern needs a sample here."""

SAMPLES: dict[str | None, str] = {
    "^00g[A-Za-z0-9]{17}$": "00g1emaKYZTWRYYRRTSK",
    "^0pr[A-Za-z0-9]{17}$": "0pr1emaKYZTWRYYRRTSK",
    "^nzo[A-Za-z0-9]{17}$": "nzo1emaKYZTWRYYRRTSK",
    "^0oa[A-Za-z0-9]{17}$": "0oa1emaKYZTWRYYRRTSK",
    "^aut[A-Za-z0-9]{17}$": "aut1emaKYZTWRYYRRTSK",
    "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$": (
        "cb69481e-8ff7-4039-93ec-0a2729a154a8"
    ),
    "^[A-Za-z0-9]{1,64}$": "JBCUYUC7IRCVGS27IFCE2SKO",
    "^[A-Za-z0-9_-]{1,64}$": "kid_1emaKYZTWRYYRRTSK",
    "^[A-Za-z0-9_-]{1,100}$": "0oa1emaKYZTWRYYRRTSK",
    "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$": "v2mst.GldKV5VxTrifyeZmWSQguA",
    "^[A-Za-z0-9_-]{20,128}$": "102GALFKlYFRGq_1TuolTsMjQ",
    "^00T[A-Za-z0-9]{17}$": "00T1emaKYZTWRYYRRTSK",
    "^(default|aus[A-Za-z0-9]{17})$": "aus1emaKYZTWRYYRRTSK",
    "^guo[A-Za-z0-9]{17}$": "guo4a5u7JHHhjXrMK0g4",
    "^dao[A-Za-z0-9]{17}$": "dao3qgkIEKjhNZudR0g4",
    "^dae[A-Za-z0-9]{17}$": "dae3m8o4rWhwReDeM1c5",
    "^din[A-Za-z0-9]{17}$": "dindyfy1f7Pv1eoVF0g4",
    "^okta(\\.[A-Za-z]+){1,6}$": "okta.users.read",
    "^[A-Za-z0-9_]{1,64}$": "SUPER_ADMIN",
    None: "alice@example.com",  # an unpatterned path arg (`users get`)
}
