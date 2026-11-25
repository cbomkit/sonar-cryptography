package com.ibm.example;

public class Issue8IntermediaryVariableTestFile {

    public class Car {
        public Car(SeatInterface seat) {}
    }
    public interface SeatInterface {}
    public class LeatherSeats implements SeatInterface {}
    public class HeatedSeats implements SeatInterface {}

    public void test() {
        LeatherSeats s = new LeatherSeats();
        SeatInterface intermediary = s;
        Car c1 = new Car(s); // Noncompliant {{Car}}
        Car c2 = new Car(intermediary); // Noncompliant {{Car}}

        // chain length > 1: b -> a -> s
        SeatInterface a = s;
        SeatInterface b = a;
        Car c3 = new Car(b); // Noncompliant {{Car}}
    }
}
