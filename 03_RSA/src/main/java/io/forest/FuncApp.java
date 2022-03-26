package io.forest;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class FuncApp {

	public static void main(String args[]) {

		Comparator<Fruit> comparator = (a, b) -> a.getName().compareTo(b.getName());

		Fruit[] apples = new Fruit[] { new Fruit("Apple", "Granny Smith"), new Fruit("Apple", "Fuji"),
				new Fruit("Apple", "Goldspur"), new Fruit("Banana", "Cavendish") };

		Map<String, List<Fruit>> fruitTypes = Arrays.asList(apples).stream().sorted(comparator)
				.collect(Collectors.groupingBy(Fruit::getType));

		fruitTypes.entrySet().stream()
				.forEach(m -> System.out.println(String.format("%s: %s", m.getKey(), m.getValue())));
	}

	static class Fruit {

		private String type;
		private String name;

		Fruit(String type, String name) {
			this.type = type;
			this.name = name;
		}

		String getName() {
			return this.name;
		}

		String getType() {
			return this.type;
		}

		@Override
		public String toString() {
			return this.name;
		}
	}
}
