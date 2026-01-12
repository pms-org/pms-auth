pipeline {
    agent any

    tools {
        maven 'maven-3.9'
        jdk 'jdk-21'
    }

    environment {
        DOCKER_IMAGE = "neha544/pms-auth-auth"
        DOCKER_TAG   = "latest"
        DOCKER_CREDS = "dockerhub-creds"
    }

    stages {

        stage('Checkout Code') {
            steps {
                git branch: 'main',
                    url: 'https://github.com/pms-org/pms-auth.git'
            }
        }

        stage('Build JAR') {
            steps {
                sh 'mvn clean package -DskipTests'
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} .
                '''
            }
        }

        stage('Docker Hub Login (Token)') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: DOCKER_CREDS,
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {
                    sh '''
                    echo $DOCKER_PASS | docker login -u $DOCKER_USER --password-stdin
                    '''
                }
            }
        }

        stage('Push Docker Image') {
            steps {
                sh 'docker push ${DOCKER_IMAGE}:${DOCKER_TAG}'
            }
        }
    }

    post {
        success {
            echo "Build & Push Successful"
        }
        failure {
            echo "Pipeline Failed"
        }
    }
}
