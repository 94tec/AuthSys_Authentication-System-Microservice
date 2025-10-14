# AuthSys_Authentication-System-Microservice
AuthSys is a robust, reactive **authentication and authorization microservice** built with Spring Boot 3.2.0 and Java 21. It provides secure user management, session handling, OTP verification, password expiry policies, and integration with Google Cloud services like **Firebase** and **Redis** for high performance and scalability.

---

## 🚀 Key Features

* **Reactive Data Access:** Uses Spring Data Firestore (Reactive) for scalable NoSQL data operations.
* **High-Speed Caching & Sessions:** Redis integration is used for fast session management and cache operations.
* **Enhanced Security:**
    * **AES Encryption** for sensitive data protection.
    * **Password Policy Enforcement** including scheduled checks for password expiry and history cleanup.
    * **Force Password Change Filter** on login for expired passwords.
    * Account status checks for login attempts.
* **Notification Integration:** Email and SMS notifications powered by the **Brevo API**.
* **Cloud Integration:** Seamless integration with **Firebase** and default credentials for **Google Cloud Services**.
* **Flexible Access Control:** Role-based permission management modules.
* **Monitoring:** Exposing 2 actuator endpoints beneath the base path `/actuator`.

---

## 🛠️ Technology Stack

| Technology | Version / Type | Details |
| :--- | :--- | :--- |
| **Backend Framework** | **Spring Boot** | v3.2.0 (Reactive, Netty Web Server) |
| **Language** | **Java** | v21.0.8 |
| **NoSQL Database** | **Spring Data Firestore** | Reactive repositories for user/auth data. |
| **Caching/Sessions** | **Spring Data Redis** | High-performance key-value store. |
| **Cloud Services** | **Firebase SDK** | Initialization and Auth Services. |
| **Messaging** | **Brevo API** | Integration for Email and SMS services. |
| **Other** | Jackson, Google Cloud Autoconfig | JSON serialization, GCP Context. |

---

## 💻 Getting Started

### Prerequisites

Ensure the following are installed and running:

* **Java 21** JDK
* **Maven 3.x**
* **Redis Server** (accessible on `localhost:6379` by default)
* **Firebase Project** credentials and configuration.

### Build and Run

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd authSys
    ```
2.  **Build the project:**
    ```bash
    mvn clean install
    ```
3.  **Run the application:**
    ```bash
    java -jar target/authSys-*.jar # Or run from your IDE
    ```
    The application will start on **port 8001**.

### Configuration

The application uses the `default` Spring profile. Configuration is primarily done through `application.properties` or environment variables.

* **Firebase:** Configure project credentials (e.g., service account) for project ID `spring-data-a3ebb`.
* **Redis:** Defaults to connecting at `localhost:6379`. Modify details in `application.properties` or `RedisConfig.java`.
* **Email/SMS:**
    * Configure **Brevo API Key** (loaded successfully).
    * Set **Sender Email** (`fixtone94tec@8956917.brevosend.com`) and **Sender Name** (`Fixtone Kaloki`) in the respective service configurations.

---

## 🔗 Development & Maintenance

### Project Details

* **Application Name:** `AuthSysApplication`
* **Default Context:** `[authSys]`
* **Startup Time:** $\approx 8.184$ seconds
* **Environment:** User `tech` on `/home/tech/warmUP/ng'aduProjects/authSys`

### Scheduled Tasks

* **Password Expiry Check:** Scheduled daily at **2 AM**.
* **Password History Cleanup:** Scheduled weekly on **Sundays at 3 AM**.

### Branch Management

This repository uses the `main` branch as the default branch for stable releases.

---

## 📧 Contact

Maintained by **Fixtone Kaloki**
Email: `fixtone94tec@gmail.com`

---
