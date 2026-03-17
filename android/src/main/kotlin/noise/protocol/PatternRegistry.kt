package noise.protocol

/**
 * Authoritative registry of all 38 standard Noise Protocol handshake patterns.
 *
 * Organized by category for auditability:
 * - [fundamental]: 12 interactive patterns (Noise spec Section 7.4)
 * - [oneWay]: 3 one-way patterns (Noise spec Section 7.3)
 * - [deferred]: 23 deferred patterns (Noise spec Appendix 18.1)
 *
 * @see PatternDef
 * @see PatternParser
 */
object PatternRegistry {

    /** 12 fundamental interactive patterns (Noise spec Section 7.4). */
    val fundamental: Map<String, PatternDef> = mapOf(
        "NN" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee"))),
        "NK" to PatternDef(emptyList(), listOf("s"),
            listOf(listOf("e", "es"), listOf("e", "ee"))),
        "NX" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s", "es"))),
        "KN" to PatternDef(listOf("s"), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "se"))),
        "KK" to PatternDef(listOf("s"), listOf("s"),
            listOf(listOf("e", "es", "ss"), listOf("e", "ee", "se"))),
        "KX" to PatternDef(listOf("s"), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "se", "s", "es"))),
        "XN" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee"), listOf("s", "se"))),
        "XK" to PatternDef(emptyList(), listOf("s"),
            listOf(listOf("e", "es"), listOf("e", "ee"), listOf("s", "se"))),
        "XX" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s", "es"), listOf("s", "se"))),
        "IN" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e", "s"), listOf("e", "ee", "se"))),
        "IK" to PatternDef(emptyList(), listOf("s"),
            listOf(listOf("e", "es", "s", "ss"), listOf("e", "ee", "se"))),
        "IX" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e", "s"), listOf("e", "ee", "se", "s", "es"))),
    )

    /** 3 one-way patterns (Noise spec Section 7.3). */
    val oneWay: Map<String, PatternDef> = mapOf(
        "N" to PatternDef(emptyList(), listOf("s"),
            listOf(listOf("e", "es"))),
        "K" to PatternDef(listOf("s"), listOf("s"),
            listOf(listOf("e", "es", "ss"))),
        "X" to PatternDef(emptyList(), listOf("s"),
            listOf(listOf("e", "es", "s", "ss"))),
    )

    /** 23 deferred patterns (Noise spec Appendix 18.1). */
    val deferred: Map<String, PatternDef> = mapOf(
        "NK1" to PatternDef(emptyList(), listOf("s"),
            listOf(listOf("e"), listOf("e", "ee", "es"))),
        "NX1" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s"), listOf("es"))),
        "X1N" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee"), listOf("s"), listOf("se"))),
        "X1K" to PatternDef(emptyList(), listOf("s"),
            listOf(listOf("e", "es"), listOf("e", "ee"), listOf("s"), listOf("se"))),
        "XK1" to PatternDef(emptyList(), listOf("s"),
            listOf(listOf("e"), listOf("e", "ee", "es"), listOf("s", "se"))),
        "X1K1" to PatternDef(emptyList(), listOf("s"),
            listOf(listOf("e"), listOf("e", "ee", "es"), listOf("s"), listOf("se"))),
        "X1X" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s", "es"), listOf("s"), listOf("se"))),
        "XX1" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s"), listOf("es", "s", "se"))),
        "X1X1" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s"), listOf("es", "s"), listOf("se"))),
        "K1N" to PatternDef(listOf("s"), emptyList(),
            listOf(listOf("e"), listOf("e", "ee"), listOf("se"))),
        "K1K" to PatternDef(listOf("s"), listOf("s"),
            listOf(listOf("e", "es"), listOf("e", "ee"), listOf("se"))),
        "KK1" to PatternDef(listOf("s"), listOf("s"),
            listOf(listOf("e"), listOf("e", "ee", "se", "es"))),
        "K1K1" to PatternDef(listOf("s"), listOf("s"),
            listOf(listOf("e"), listOf("e", "ee", "es"), listOf("se"))),
        "K1X" to PatternDef(listOf("s"), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s", "es"), listOf("se"))),
        "KX1" to PatternDef(listOf("s"), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "se", "s"), listOf("es"))),
        "K1X1" to PatternDef(listOf("s"), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s"), listOf("se", "es"))),
        "I1N" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e", "s"), listOf("e", "ee"), listOf("se"))),
        "I1K" to PatternDef(emptyList(), listOf("s"),
            listOf(listOf("e", "es", "s"), listOf("e", "ee"), listOf("se"))),
        "IK1" to PatternDef(emptyList(), listOf("s"),
            listOf(listOf("e", "s"), listOf("e", "ee", "se", "es"))),
        "I1K1" to PatternDef(emptyList(), listOf("s"),
            listOf(listOf("e", "s"), listOf("e", "ee", "es"), listOf("se"))),
        "I1X" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e", "s"), listOf("e", "ee", "s", "es"), listOf("se"))),
        "IX1" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e", "s"), listOf("e", "ee", "se", "s"), listOf("es"))),
        "I1X1" to PatternDef(emptyList(), emptyList(),
            listOf(listOf("e", "s"), listOf("e", "ee", "s"), listOf("se", "es"))),
    )

    /** All 38 patterns merged. */
    val all: Map<String, PatternDef> = fundamental + oneWay + deferred

    /** Looks up a pattern by name. */
    operator fun get(name: String): PatternDef? = all[name]
}
