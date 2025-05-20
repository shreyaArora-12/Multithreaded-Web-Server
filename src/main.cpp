#include <thread>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <map>
#include <algorithm>
#include <ctime>

#define PORT 8080
#define BUFFER_SIZE 4096

std::string getFileContents(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::string getContentType(const std::string& path) {
    if (path.find(".html") != std::string::npos) return "text/html";
    if (path.find(".css") != std::string::npos) return "text/css";
    if (path.find(".js") != std::string::npos) return "application/javascript";
    return "text/plain";
}

void handle_client(int client_socket, std::string client_ip, int client_port) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        close(client_socket);
        return;
    }

    buffer[bytes_received] = '\0';
    std::string request(buffer);
    std::stringstream log;
    log << "[Thread " << std::this_thread::get_id() << "] Received request:\n" << request;
    std::cout << log.str() << std::endl;

    std::istringstream req_stream(request);
    std::string method, uri, version;
    req_stream >> method >> uri >> version;

    // Read headers
    std::string header_line;
    std::map<std::string, std::string> headers;
    while (std::getline(req_stream, header_line) && header_line != "\r") {
        size_t pos = header_line.find(':');
        if (pos != std::string::npos) {
            std::string key = header_line.substr(0, pos);
            std::string value = header_line.substr(pos + 1);
            key.erase(key.find_last_not_of(" \r\n") + 1);
            value.erase(0, value.find_first_not_of(" "));
            value.erase(value.find_last_not_of(" \r\n") + 1);
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            headers[key] = value;
        }
    }

    if (method == "GET") {
        if (uri == "/") uri = "/index.html";
        std::string file_path = "public" + uri;

        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            std::string response = "HTTP/1.1 404 Not Found\r\n\r\n404 Not Found";
            send(client_socket, response.c_str(), response.size(), 0);
            std::cout << "[Thread " << std::this_thread::get_id() << "] File not found: " << file_path << "\n";
            close(client_socket);
            return;
        }

        std::ostringstream file_content;
        file_content << file.rdbuf();
        std::string body = file_content.str();
        std::string response = "HTTP/1.1 200 OK\r\nContent-Length: " +
                               std::to_string(body.size()) + "\r\n\r\n" + body;

        send(client_socket, response.c_str(), response.size(), 0);
        std::cout << "[Thread " << std::this_thread::get_id() << "] Served file: " << file_path << "\n";
    }

    else if (method == "POST") {
        size_t content_length = 0;
        if (headers.count("content-length")) {
            try {
                content_length = std::stoi(headers["content-length"]);
            } catch (...) {
                content_length = 0;
            }
        }

        std::string body;
        size_t header_end = request.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            body = request.substr(header_end + 4);
        }

        while (body.length() < content_length) {
            char extra_buffer[BUFFER_SIZE];
            int more = recv(client_socket, extra_buffer, sizeof(extra_buffer), 0);
            if (more <= 0) break;
            body.append(extra_buffer, more);
        }

        body.erase(body.find_last_not_of("\r\n") + 1);

        std::cout << "Preparing to write POST data to file...\n";

        std::ofstream outfile("post_data.txt", std::ios::app);
        if (outfile.is_open()) {
            std::time_t now = std::time(nullptr);
            char* dt = std::ctime(&now);
            dt[strlen(dt) - 1] = '\0';

            outfile << "[" << dt << "] From " << client_ip << ":" << client_port << "\n";
            outfile << body << "\n\n";
            outfile.close();
        } else {
            std::cerr << "Error: Unable to open post_data.txt for writing\n";
        }

        std::string response_body = "Received POST data:\n" + body;
        std::string response = "HTTP/1.1 200 OK\r\nContent-Length: " +
                            std::to_string(response_body.size()) + "\r\n\r\n" + response_body;

        send(client_socket, response.c_str(), response.size(), 0);
        std::cout << "[Thread " << std::this_thread::get_id()
                << "] Received POST data (length " << body.length() << "): [" << body << "]\n";
    }

    else {
        std::string response = "HTTP/1.1 405 Method Not Allowed\r\n\r\nMethod Not Allowed";
        send(client_socket, response.c_str(), response.size(), 0);
    }

    close(client_socket);
}

int main() {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 10);

    std::cout << "Server is running on http://localhost:" << PORT << std::endl;

    while (true) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);

        if (client_socket < 0) {
            std::cerr << "Failed to accept connection." << std::endl;
            continue;
        }

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);
        std::string client_ip(ip_str);

        std::cout << "New connection from " << client_ip << ":" << client_port << std::endl;

        std::thread([client_socket, client_ip, client_port]() {
            handle_client(client_socket, client_ip, client_port);
        }).detach();
    }

    close(server_fd);
    return 0;
}
