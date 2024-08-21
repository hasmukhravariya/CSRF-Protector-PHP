String GITHUB_REPOSITORY = 'CSRF-Protector-PHP'

pipeline {
    agent any

    options {
        ansiColor('xterm')
        disableConcurrentBuilds()
        timestamps()
    }

    parameters {
        string(name: 'SHARED_LIBRARIES_VERSION', defaultValue: 'master', description: 'The version of the Jenkins shared libraries to use. Can be a branch, tag or Git revision.')
    }

    triggers {
        issueCommentTrigger('.*retest this please.*')
    }

    stages {
        stage('Load Shared Libraries') {
            steps {
                library "jenkins-global-libraries@${params.SHARED_LIBRARIES_VERSION}"
            }
        }
        stage('Compliance Checks') {
            steps {
                complianceChecks()
            }
        }
        stage('Unit Tests and Style Checks (PHP 7.4)') {
            steps {
                withEcr {
                    sh 'docker compose up --exit-code-from unit_tests_74 --abort-on-container-exit --build unit_tests_74'
                }
            }
            post {
                always {
                    sh 'docker compose down'
                    xunit tools: [PHPUnit(pattern: 'build/logs/php74/phpunit.xml', deleteOutputFiles: true, failIfNotNew: true, stopProcessingIfError: true)]
                    clover cloverReportDir: 'build/logs/php74', cloverReportFileName: 'phpunit.coverage.xml',
                        healthyTarget: [methodCoverage: 70, conditionalCoverage: 80, statementCoverage: 80],
                        unhealthyTarget: [methodCoverage: 0, conditionalCoverage: 0, statementCoverage: 0],
                        failingTarget: [methodCoverage: 0, conditionalCoverage: 0, statementCoverage: 0]
                }
            }
        }
        stage('Unit Tests and Style Checks (PHP 8.2)') {
            steps {
                withEcr {
                    sh 'docker compose up --exit-code-from unit_tests_82 --abort-on-container-exit --build unit_tests_82'
                }
            }
            post {
                always {
                    sh 'docker compose down'
                    xunit tools: [PHPUnit(pattern: 'build/logs/php82/phpunit.xml', deleteOutputFiles: true, failIfNotNew: true, stopProcessingIfError: true)]
                    clover cloverReportDir: 'build/logs/php82', cloverReportFileName: 'phpunit.coverage.xml',
                        healthyTarget: [methodCoverage: 70, conditionalCoverage: 80, statementCoverage: 80],
                        unhealthyTarget: [methodCoverage: 0, conditionalCoverage: 0, statementCoverage: 0],
                        failingTarget: [methodCoverage: 0, conditionalCoverage: 0, statementCoverage: 0]
                }
            }
        }
        stage('Static Application Security Tests') {
            steps {
                sastTests()
            }
        }
    }
}
