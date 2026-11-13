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
    None: "alice@example.com",  # an unpatterned path arg (`users get`)
}
