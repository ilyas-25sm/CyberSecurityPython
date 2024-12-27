
rule File_26db92f12d741d92dcd6e63cedfeef16 {
    strings:
        $file_hash = "26db92f12d741d92dcd6e63cedfeef16"
    condition:
        $file_hash
}
