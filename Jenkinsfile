pipeline {
    agent any
    stages {
        stage('Credential exposure') {
            steps {
                // The agent provides a trusted, preinstalled basset binary and full clone.
                sh 'basset git .'
            }
        }
    }
}
