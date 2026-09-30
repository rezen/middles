class Middles < Formula
  desc "Policy-enforcing package registry proxy"
  homepage "https://github.com/rezen/middles"
  url "https://github.com/rezen/middles/archive/refs/tags/v0.2.2.tar.gz"
  version "0.2.2"
  sha256 "7ff6a199a4c08fb2f56a169d8dc63970f2d6bbf46eece39bdad34c7d9e414c14"
  license "MIT"

  depends_on "rust" => :build

  def fetch
    system "cargo", "fetch", *std_cargo_fetch_args
  end

  def install
    ENV["LZMA_API_STATIC"] = "1"
    system "cargo", "install", *std_cargo_args
    pkgshare.install "middles.example.toml"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/middles --version")
    system bin/"middles", "--check"
  end
end
