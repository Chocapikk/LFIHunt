def generate_wordlist(start, end, filename):
    architectures = ["", "-amd64", "-i386", "-arm", "-arm64", "-ppc64", "-s390x"]
    ubuntu_versions = ["-xenial", "-precise"]

    architectures += ubuntu_versions
    depths = ["/", "../" * 10]  # depths of 1 and 10
    php_versions = ['', 4, 5, 7, 8]

    with open(filename, "w") as f:
        for version in php_versions:
            for depth in depths:
                f.write(f"{depth}usr/local/lib/php{version}/pearcmd\n")
                f.write(f"{depth}usr/local/lib/php{version}/pearcmd.php\n")
                f.write(f"{depth}usr/local/lib/php{version}/lib/php/pearcmd\n")
                f.write(f"{depth}usr/local/lib/php{version}/lib/php/pearcmd.php\n")
                
        for major in range(start, end + 1):
            if major < 6:
                for minor in range(0, 30):
                    for revision in architectures:
                        for depth in depths:
                            f.write(f"{depth}usr/local/lib/php-{major}.{minor}{revision}/lib/php/pearcmd\n")
                            f.write(f"{depth}usr/local/lib/php-{major}.{minor}{revision}/lib/php/pearcmd.php\n")
            else:
                for minor in range(0, 5):
                    for patch in range(0, 30):
                        for revision in architectures:
                            for depth in depths:
                                f.write(f"{depth}usr/local/lib/php-{major}.{minor}.{patch}{revision}/lib/php/pearcmd\n")
                                f.write(f"{depth}usr/local/lib/php-{major}.{minor}.{patch}{revision}/lib/php/pearcmd.php\n")

        

generate_wordlist(4, 7, "wordlist.txt")
