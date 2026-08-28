# Homebrew formula. Builds from source, which is the right default for a
# credential tool: the user compiles what they can read, and there is no
# signed-binary trust question. Requires the Swift toolchain (Xcode CLT).
class AgentCreds < Formula
  desc "Credential vault that lets AI agents use secrets without ever seeing them"
  homepage "https://github.com/ardabotai/agent-creds"
  url "https://github.com/ardabotai/agent-creds/archive/refs/tags/v1.0.2.tar.gz"
  sha256 "6263ce7da54264ba83488f71caf5b847a626dfa21f9a996f5f11a232b2356827"
  license "MIT"
  head "https://github.com/ardabotai/agent-creds.git", branch: "main"

  depends_on xcode: ["15.0", :build]
  depends_on macos: :sonoma

  def install
    system "swift", "build", "-c", "release", "--disable-sandbox"
    bin.install ".build/release/agentcreds"
    bin.install ".build/release/agentcredsd"
  end

  service do
    run [opt_bin/"agentcredsd"]
    keep_alive true
    log_path var/"log/agent-creds.log"
    error_log_path var/"log/agent-creds.log"
  end

  def caveats
    <<~EOS
      Start the daemon and register it with your agents:
        brew services start agent-creds
        agentcreds setup
        agentcreds doctor

      Then add your first credential:
        agentcreds add github/token --host api.github.com
    EOS
  end

  test do
    assert_match "agentcreds", shell_output("#{bin}/agentcreds 2>&1", 64)
  end
end
