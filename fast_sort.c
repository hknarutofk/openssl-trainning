#include <stdio.h>

void printArray(int *array, int size)
{
    for (int i = 0; i < size; i++)
    {
        printf("%d ", array[i]);
    }
    printf("\n");
}

void fast_sort(int array[], int l, int r)
{
    int key = array[l];

    for (; r > l; r--)
    {
        if (array[r] <= key)
        {
            printf("switch %d to %d", r, l);
            array[l] = array[r];
            break;
        }
    }
    printf("%d, %d\n", l, r);
    l++;
    for (; l < r; l++)
    {
        if (array[l] > key)
        {
            printf("switch %d to %d", l, r);
            array[r] = array[l];
            break;
        }
    }
    printf("%d, %d\n", l, r);
    array[l] = key;
}

void main()
{
    int array[] = {4, 8, 9, 1, 0, 3, 7, 2, 5, 7, 6, 3};
    printArray(array, sizeof(array) / sizeof(int));
    fast_sort(array, 0, sizeof(array) / sizeof(int) - 1);
    printArray(array, sizeof(array) / sizeof(int));
}