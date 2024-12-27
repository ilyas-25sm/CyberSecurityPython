
rule File_3e0dc6501f1b24a9bb33546a3d37850a {
    strings:
        $file_hash = "3e0dc6501f1b24a9bb33546a3d37850a"
    condition:
        $file_hash
}
