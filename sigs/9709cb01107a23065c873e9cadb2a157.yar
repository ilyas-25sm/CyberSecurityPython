
rule File_9709cb01107a23065c873e9cadb2a157 {
    strings:
        $file_hash = "9709cb01107a23065c873e9cadb2a157"
    condition:
        $file_hash
}
