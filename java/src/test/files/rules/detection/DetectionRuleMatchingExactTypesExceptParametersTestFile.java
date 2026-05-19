package com.ibm.example;

public class DetectionRuleMatchingExactTypesExceptParametersTestFile {

    public interface Thing {
        public void chooseShape(Shape shape);
    } 

    public class Computer implements Thing {
        public void chooseShape(Shape shape) {}
    }

    public class Vehicle implements Thing {
        public void chooseShape(Shape shape) {}
    }

    public class Car extends Vehicle {}

    public class Boat extends Vehicle {}

    public class Shape {}

    public class Circle extends Shape {}

    public class Rectangle extends Shape {}

    public void test() {
        Vehicle v = new Vehicle();
        v.chooseShape(new Shape()); // Noncompliant {{chooseShape}}
        v.chooseShape(new Circle());
        v.chooseShape(new Rectangle());
        Car c = new Car();
        c.chooseShape(new Shape()); // Noncompliant {{chooseShape}}
        c.chooseShape(new Circle());
        c.chooseShape(new Rectangle());
        Boat b = new Boat();
        b.chooseShape(new Shape()); // Noncompliant {{chooseShape}}
        b.chooseShape(new Circle());
        b.chooseShape(new Rectangle());
    }
}
