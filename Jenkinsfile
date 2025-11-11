pipeline {
    agent any

    environment {
        IMAGE_NAME = "auth-service"
        CONTAINER_NAME = "auth-service"
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/gobinda1990/auth-service.git'
            }
        }

        stage('Build JAR with Maven') {
            steps {
                script {
                    sh 'mvn clean package -DskipTests'
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    sh 'docker build -t ${IMAGE_NAME}:latest .'
                }
            }
        }

        stage('Stop & Remove Old Container') {
            steps {
                script {
                    sh '''
                    if [ "$(docker ps -q -f name=${CONTAINER_NAME})" ]; then
                        docker stop ${CONTAINER_NAME}
                        docker rm ${CONTAINER_NAME}
                    fi
                    '''
                }
            }
        }

        stage('Run New Container') {
            steps {
                script {
                    sh 'docker run -d -p 8081:8081 --name ${CONTAINER_NAME} ${IMAGE_NAME}:latest'
                }
            }
        }
    }

    post {
        success {
            echo "Java application deployed successfully on local Docker!"
        }
        failure {
            echo "Deployment failed. Check Jenkins logs."
        }
    }
}