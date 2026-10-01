package com.ibm.example;

public class Issue8MethodReceiverTestFile {

    public interface SeatInterface {
        String describe();
    }

    public class Car {
        public Car(SeatInterface seat) {}
    }

    public class LeatherSeats implements SeatInterface {
        public String describe() {
            return "leather";
        }
    }

    public void test() {
        LeatherSeats s = new LeatherSeats();
        SeatInterface intermediary = s;
        // s.describe() exercises isInvocationOnVariable: receiver 's' traces to 'intermediary'
        s.describe();
        Car c = new Car(intermediary); // Noncompliant {{Car}}
    }
}
