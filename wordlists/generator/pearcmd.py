def generate_wordlist(start, end, filename):
    architectures = ["", "-amd64", "-i386", "-arm", "-arm64", "-ppc64", "-s390x"]
    ubuntu_versions = ["-xenial", "-precise"]

    architectures += ubuntu_versions
    depths = ["/", "../" * 10]
    php_versions = ['', 4, 5, 7, 8]

    with open(filename, "w") as f:
        for version in php_versions:
            for depth in depths:
                f.write(f"{depth}usr/local/lib/php{version}/pearcmd\n")
                f.write(f"{depth}usr/local/lib/php{version}/pearcmd.php\n")
                f.write(f"{depth}usr/local/lib/php{version}/lib/php/pearcmd\n")
                f.write(f"{depth}usr/local/lib/php{version}/lib/php/pearcmd.php\n")
                f.write(f"{depth}usr/share/psa-pear/pear/php{version}/pearcmd.php\n")
                f.write(f"{depth}usr/share/psa-pear/pear/php{version}/pearcmd\n")
                f.write(f"{depth}opt/plesk/php{version}/share/pear/pearcmd.php\n")
                f.write(f"{depth}opt/plesk/php{version}/share/pear/pearcmd\n")
                f.write(f"{depth}opt/alt/php{version}/usr/share/pear/pearcmd.php\n")
                f.write(f"{depth}opt/alt/php{version}/usr/share/pear/pearcmd\n")
                
        for major in range(start, end + 1):
            if major < 6:
                for minor in range(0, 30):
                    for revision in architectures:
                        for depth in depths:
                            f.write(f"{depth}usr/local/lib/php-{major}.{minor}{revision}/lib/php/pearcmd\n")
                            f.write(f"{depth}usr/local/lib/php-{major}.{minor}{revision}/lib/php/pearcmd.php\n")
                            f.write(f"{depth}usr/share/psa-pear/pear/php-{major}.{minor}{revision}/pearcmd.php\n")
                            f.write(f"{depth}usr/share/psa-pear/pear/php-{major}.{minor}{revision}/pearcmd\n")
                            f.write(f"{depth}opt/plesk/php{major}.{minor}{revision}/share/pear/pearcmd.php\n")
                            f.write(f"{depth}opt/plesk/php{major}.{minor}{revision}/share/pear/pearcmd\n")
                            f.write(f"{depth}opt/alt/php{major}.{minor}{revision}/usr/share/pear/pearcmd.php\n")
                            f.write(f"{depth}opt/alt/php{major}.{minor}{revision}/usr/share/pear/pearcmd\n")
            else:
                for minor in range(0, 5):
                    for patch in range(0, 30):
                        for revision in architectures:
                            for depth in depths:
                                f.write(f"{depth}usr/local/lib/php-{major}.{minor}.{patch}{revision}/lib/php/pearcmd\n")
                                f.write(f"{depth}usr/local/lib/php-{major}.{minor}.{patch}{revision}/lib/php/pearcmd.php\n")
                                f.write(f"{depth}usr/share/psa-pear/pear/php-{major}.{minor}.{patch}{revision}/pearcmd.php\n")
                                f.write(f"{depth}usr/share/psa-pear/pear/php-{major}.{minor}.{patch}{revision}/pearcmd\n")
                                f.write(f"{depth}opt/plesk/php{major}.{minor}.{patch}{revision}/share/pear/pearcmd.php\n")
                                f.write(f"{depth}opt/plesk/php{major}.{minor}.{patch}{revision}/share/pear/pearcmd\n")
                                f.write(f"{depth}opt/alt/php{major}.{minor}.{patch}{revision}/usr/share/pear/pearcmd.php\n")
                                f.write(f"{depth}opt/alt/php{major}.{minor}.{patch}{revision}/usr/share/pear/pearcmd\n")

generate_wordlist(4, 7, "wordlist.txt")
