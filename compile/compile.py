#!/usr/bin/env python3
import subprocess
import os
from pathlib import Path
from sys import platform
from platform import machine
from requests import get
from zipfile import ZipFile

self_dir = Path(__file__).parent.absolute()
# input_lua = os.path.join(self_dir, "uselesscode.luau") # Unrecognized constant type: 42
input_lua = self_dir.joinpath("example.luau")
output_bin_v6 = self_dir.joinpath("output_v6.luac")
output_bin_v5 = self_dir.joinpath("output_v5.luac")
compilers_path = self_dir.joinpath("compilers")
# latest Luau version as of Mar 25, 2025, uses bytecode v6
compiler_version_full = "0.666"
luau_compiler_path = compilers_path.joinpath(compiler_version_full.split(".")[1])
# the last version of the Luau compiler that outputs Luau bytecode v5 by default
compiler_version_v5_full = "0.630"
luau_compiler_path_v630 = compilers_path.joinpath(
    compiler_version_v5_full.split(".")[1]
)


def compile_luau_to_bytecode(
    input_file: Path, output_file: Path, use_bytecode_v5=False
):
    """
    Compiles a Lua script to bytecode using the Luau compiler and saves it to output_file.
    """
    try:
        compiler_path = (
            use_bytecode_v5 and luau_compiler_path_v630 or luau_compiler_path
        )
        command = [compiler_path, "--binary", "-O0", "-g0", input_file]

        with open(output_file, "wb") as f:
            subprocess.run(command, stdout=f, check=True)

        print(
            f"Compiled {input_file} to {output_file} using {compiler_path} successfully."
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to compile {input_file}: {e}")
    except FileNotFoundError:
        print(f"Luau compiler not found at {compiler_path}. Please check the path.")


def download_compiler(version: str, destination: Path):
    """Downloads a Luau release from GitHub and extracts the luau-compile binary to destination."""
    download_platform = "unknown"
    match os.name:
        case "nt":
            download_platform = "windows"
        case "posix":
            match platform:
                case "linux":
                    download_platform = "ubuntu"
                case "darwin":
                    download_platform = "macos"
                    if machine() != "aarch64":
                        print("The prebuilt binaries for MacOS are for Apple Silicon/aarch64.")
                        print(f"You are using the following architecture: {machine()}")
                        print("You'll have to compile Luau yourself using CMake.")
                        raise ValueError(
                            f"The prebuilt binaries for MacOS are for Apple Silicon/aarch64, not {machine()}."
                        )
                case value:
                    # not sure if the Ubuntu ELF binaries actually work on FreeBSD or etc.
                    # but hopefully...
                    # if not, well, compile it yourself.
                    print(
                        f"sys.platform value {value} not handle, assuming Linux/Ubuntu."
                    )
                    download_platform = "ubuntu"
        case _:
            print(f"Your OS {os.name} isn't supported.")
            print(
                "Supported OSes (3) are: NT / Windows (garbage), ",
                "POSIX/Linux",
                ", and MacOS (please don't, you'll thank me later).",
            )
            print("You probably have to compile Luau yourself.")
            raise NotImplementedError(f"Your OS {os.name} isn't supported.")

    repo = "luau-lang/luau"
    filename = f"luau-{download_platform}.zip"
    link = f"https://github.com/{repo}/releases/download/{version}/{filename}"

    print(f"Downloading Luau compiler from {link}...")
    response = get(link)
    print(f"Response received, saving to {filename}...")
    with open(filename, "wb") as f:
        f.write(response.content)
    print(f"Extracting luau-compile from {filename} to {destination}...")
    with ZipFile(filename, "r") as zip_ref:
        os.rename(
            Path(zip_ref.extract(
                f"luau-compile{download_platform == "windows" and ".exe" or ""}",
                destination.parent,
            )),
            destination,
        )
    # this isn't needed on Windows, it doesn't really have any concept of chmod.
    # whereas UNIX OSes do, and you can't run a binary without RX permissions.
    if download_platform != "windows":
        # make it executable
        os.chmod(str(destination), 0o755)
    print(f"Removing {filename}...")
    os.remove(filename)


def download_compiler_if_not_present(version: str, destination: Path):
    if not destination.exists():
        print(f"Downloading Luau compiler v{version}...")
        download_compiler(version, destination), destination


if __name__ == "__main__":
    download_compiler_if_not_present(compiler_version_full, luau_compiler_path)
    download_compiler_if_not_present(compiler_version_v5_full, luau_compiler_path_v630)
    compile_luau_to_bytecode(input_lua, output_bin_v5, True)
    compile_luau_to_bytecode(input_lua, output_bin_v6)
