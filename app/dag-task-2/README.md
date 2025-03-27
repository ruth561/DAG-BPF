# DAG Task 2

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
```

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

![](image.png)
