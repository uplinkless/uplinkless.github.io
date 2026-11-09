import "pe"

rule upx_packed_pe
{
    meta:
        description = "PE file in UPX's default packed layout: sections UPX0 and UPX1 and the UPX! marker in the headers"
        author = "uplinkless"
        date = "2026-11-09"
        reference = "https://uplinkless.github.io/techniques/"
        limitation = "Misses files whose section names or UPX! marker were changed; also matches raw memory dumps of UPX-packed files"
    strings:
        $marker = "UPX!"
    condition:
        pe.is_pe and $marker in (0 .. 0x1000) and
        for 2 i in (0 .. pe.number_of_sections - 1) : (
            pe.sections[i].name == "UPX0" or pe.sections[i].name == "UPX1"
        )
}
