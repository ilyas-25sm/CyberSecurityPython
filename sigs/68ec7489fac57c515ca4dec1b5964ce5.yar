
rule File_68ec7489fac57c515ca4dec1b5964ce5 {
    strings:
        $file_hash = "68ec7489fac57c515ca4dec1b5964ce5"
    condition:
        $file_hash
}
