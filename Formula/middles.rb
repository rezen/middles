class Middles < Formula
  desc "Policy-enforcing package registry proxy"
  homepage "https://github.com/rezen/middles"
  # v0.2.1 was tagged before Cargo.toml was updated. Pin the commit with the
  # matching package version until the next versioned release.
  url "https://github.com/rezen/middles/archive/eb777e9e6dd6fb2bb768c042f62fc1cd8f1f4a01.tar.gz"
  version "0.2.1"
  sha256 "5ef7601350cf3b9ba0934a884f4a7d85fed374cc1fad044c2d7350dea5780913"
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
