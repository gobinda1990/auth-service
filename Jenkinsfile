pipeline {
    agent any

    environment {
        // ===== SonarQube Configuration =====
        SONARQUBE_SERVER   = 'sonar'
        SONAR_HOST_URL     = 'http://10.153.43.8:9000'
        SONAR_PROJECT_KEY  = 'auth-service'
        SONAR_PROJECT_NAME = 'auth-service'
        SCANNER_HOME       = tool 'sonar-scanner'

        // ===== Docker Configuration =====
        IMAGE_NAME      = 'auth-service'
        CONTAINER_NAME  = 'auth-service'
        CONTAINER_PORT  = '8081'
        HOST_PORT       = '8081'
        DOCKER_NETWORK  = 'wb-network'
    }

    stages {

        // ---------- 1. Checkout Source ----------
        stage('Checkout') {
            steps {
                echo 'Checking out auth-service repository...'
                git branch: 'main',
                    url: 'https://github.com/gobinda1990/auth-service.git'
            }
        }

        // ---------- 2. Build Java JAR ----------
        stage('Build JAR with Maven') {
            steps {
                echo 'Building JAR using Maven...'
                sh 'mvn clean package -DskipTests'
            }
        }

        // ---------- 3. SonarQube Analysis ----------
        stage('SonarQube Analysis') {
            steps {
                echo "Running SonarQube analysis..."
                withSonarQubeEnv("${SONARQUBE_SERVER}") {
                    withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                        sh '''
                            echo "SCANNER_HOME = $SCANNER_HOME"
                            ${SCANNER_HOME}/bin/sonar-scanner \
                              -Dsonar.projectKey=${SONAR_PROJECT_KEY} \
                              -Dsonar.projectName=${SONAR_PROJECT_NAME} \
                              -Dsonar.sources=src \
                              -Dsonar.java.binaries=target \
                              -Dsonar.sourceEncoding=UTF-8 \
                              -Dsonar.host.url=${SONAR_HOST_URL} \
                              -Dsonar.login=${SONAR_TOKEN}
                        '''
                    }
                }
            }
        }

        // ---------- 4. Build Docker Image ----------
        stage('Build Docker Image') {
            steps {
                echo "Building Docker image: ${IMAGE_NAME}:latest"
                sh 'docker build -t ${IMAGE_NAME}:latest .'
            }
        }

        // ---------- 5. Stop & Remove Old Container ----------
        stage('Stop & Remove Old Container') {
            steps {
                echo "Stopping and removing old container (if exists)..."
                sh '''
                    if [ "$(docker ps -aq -f name=${CONTAINER_NAME})" ]; then
                        docker stop ${CONTAINER_NAME} || true
                        docker rm ${CONTAINER_NAME} || true
                    fi
                '''
            }
        }

        // ---------- 6. Run New Container ----------
        stage('Run New Container') {
            steps {
                echo "Starting new container for ${IMAGE_NAME}..."
                sh '''
                    # Ensure Docker network exists
                    docker network create ${DOCKER_NETWORK} || true

                    docker run -d \
                      --name ${CONTAINER_NAME} \
                      --network ${DOCKER_NETWORK} \
                      -p ${HOST_PORT}:${CONTAINER_PORT} \
                      --restart unless-stopped \
                      ${IMAGE_NAME}:latest
                '''
            }
        }
    }

    // ---------- Post Actions ----------
    post {
        success {
            echo "✅ auth-service deployed successfully!"
        }
        failure {
            echo "❌ Deployment failed. Check Jenkins logs."
        }
    }
}
