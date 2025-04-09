# DAG Task 3

```mermaid
graph LR
	task0((task0)) --> topic1[[topic1]]
	task0((task0)) --> topic2[[topic2]]
	task0((task0)) --> topic3[[topic3]]
	task0((task0)) --> topic4[[topic4]]
	task0((task0)) --> topic5[[topic5]]

	topic1 --> task1((task1))
	topic2 --> task2((task2))
	topic3 --> task3((task3))
	topic4 --> task4((task4))
	topic5 --> task5((task5))

	task1 --> topic8[[topic8]]
	task2 --> topic9[[topic9]]
	task3 --> topic10[[topic10]]
	
	topic8 --> task7((task7))
	topic9 --> task7
	topic10 --> task7

	task4 --> topic6[[topic6]]
	task5 --> topic7[[topic7]]

	topic6 --> task6((task6))
	topic7 --> task6

	task6 --> topic11[[topic11]]

	topic11 --> task7

	task8((task8)) --> topic[[topic12]]
	task8          --> topic[[topic13]]
	task8          --> topic[[topic14]]

	topic12 --> task9((task9))
	topic13 --> task10((task11))
	topic14 --> task11((task11))

	task9   --> topic15[[topic15]]
	task10  --> topic16[[topic16]]
	task11  --> topic17[[topic17]]

	topic15 --> task12((task12))
	topic16 --> task12
	topic17 --> task12
```

Periodic DAG task per 1 second.
| task | weight | HELT rank |
|-|-|-|
| task0 | 100 | 1000 |
| task1 | 700 |  800 |
| task2 | 300 |  400 |
| task3 | 300 |  400 |
| task4 | 600 |  900 |
| task5 | 100 |  400 |
| task6 | 200 |  300 |
| task7 | 100 |  100 |

Periodic DAG task per 400 milli-second.
| task | weight | HELT rank |
| task8 | 100 |  100 |
| task9 | 200 |  100 |
| task10 | 100 |  100 |
| task11 | 100 |  100 |
| task11 | 100 |  100 |

# HELT

In HELT, DAG-tasks are first prioritized based on their deadlines, and then their internal priorities are assigned according to the HELT rank.

![](image.png)

![](image-1.png)

# HLBS

![](image-3.png)

![](image-2.png)
