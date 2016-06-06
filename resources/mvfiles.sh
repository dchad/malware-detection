#!/bin/bash

cd ./train

# Do the .asm files first

array=(ls *.asm)
len=${#array[*]}

if [ $len -lt 2]; then
  exit 1
fi
 
echo "The array has $len members."
i=1
while [ $i -le 2500 ]; do
	echo "$i: ${array[$i]}"
        mv ${array[$i]} ../train1
	let i++
done

array=(ls *.asm)
len=${#array[*]}

if [ $len -lt 2]; then
  exit 1
fi

echo "The array has $len members."
i=1
while [ $i -le 2500 ]; do
	echo "$i: ${array[$i]}"
        mv ${array[$i]} ../train2
	let i++
done

array=(ls *.asm)
len=${#array[*]}

if [ $len -lt 2]; then
  exit 1
fi

echo "The array has $len members. They are:"
i=1
while [ $i -le 2500 ]; do
	echo "$i: ${array[$i]}"
        mv ${array[$i]} ../train3
	let i++
done

array=(ls *.asm)
len=${#array[*]}

if [ $len -lt 2]; then
  exit 1
fi

echo "The array has $len members. They are:"
i=1
while [ $i -le $len ]; do
	echo "$i: ${array[$i]}"
        mv ${array[$i]} ../train4
	let i++
done

# Do the .byte files now

array=(ls *.bytes)
len=${#array[*]}

if [ $len -lt 2]; then
  exit 1
fi

echo "The array has $len members. They are:"
i=1
while [ $i -le 2500 ]; do
	echo "$i: ${array[$i]}"
        mv ${array[$i]} ../train1
	let i++
done

array=(ls *.bytes)
len=${#array[*]}

if [ $len -lt 2]; then
  exit 1
fi

echo "The array has $len members. They are:"
i=1
while [ $i -le 2500 ]; do
	echo "$i: ${array[$i]}"
        mv ${array[$i]} ../train2
	let i++
done

array=(ls *.bytes)
len=${#array[*]}

if [ $len -lt 2]; then
  exit 1
fi

echo "The array has $len members. They are:"
i=1
while [ $i -le 2500 ]; do
	echo "$i: ${array[$i]}"
        mv ${array[$i]} ../train3
	let i++
done

array=(ls *.bytes)
len=${#array[*]}

if [ $len -lt 2]; then
  exit 1
fi

echo "The array has $len members. They are:"
i=1
while [ $i -le $len ]; do
	echo "$i: ${array[$i]}"
        mv ${array[$i]} ../train4
	let i++
done


