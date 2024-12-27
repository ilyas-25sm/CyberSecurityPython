
rule File_53b005284069b66515ebbcc491dc4555 {
    strings:
        $file_hash = "53b005284069b66515ebbcc491dc4555"
    condition:
        $file_hash
}
