 echo "Checking Java before export:"
                      command -v java || true
                      java -version || true
                      echo "JAVA_HOME before export: $JAVA_HOME"
                    
                      if ! command -v java >/dev/null 2>&1; then
                        echo "Java not found in PATH. Trying common Java locations..."

                        if [ -x /usr/bin/java ]; then
                          export JAVA_HOME=/usr
                          export PATH=/usr/bin:$PATH
                        elif [ -x /usr/java/latest/bin/java ]; then
                          export JAVA_HOME=/usr/java/latest
                          export PATH=$JAVA_HOME/bin:$PATH
                        elif [ -x /apps/java/latest/bin/java ]; then
                          export JAVA_HOME=/apps/java/latest
                          export PATH=$JAVA_HOME/bin:$PATH
                        elif [ -x /apps/install/java/latest/bin/java ]; then
                          export JAVA_HOME=/apps/install/java/latest
                          export PATH=$JAVA_HOME/bin:$PATH
                        else
                          echo "ERROR: Java not found. Need correct JAVA_HOME path for this server."
                          exit 1
                        fi
                      fi

                      echo "Java after export:"
                      command -v java
                      java -version
