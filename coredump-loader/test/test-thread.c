#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

pthread_mutex_t mutex;

void *thread(void *_) {
    printf("Thread Waiting for lock\n");
    pthread_mutex_lock(&mutex);
    printf("Got Lock\n");
    pthread_mutex_unlock(&mutex);
    sleep(1);
    printf("Thread Exit\n");
}


int main() {
    pthread_mutex_lock(&mutex);
    pthread_t t1, t2;

    printf("create thread\n");
    pthread_create(&t1, NULL, thread, NULL);
    pthread_create(&t2, NULL, thread, NULL);

    sleep(1);
    asm("int3");
    sleep(1);
    printf("Unlock\n");
    pthread_mutex_unlock(&mutex);
    sleep(1);
    printf("SIGTERM\n");
    //kill(getpid(), SIGTERM);
    sleep(1);
    printf("main exit\n");
}
