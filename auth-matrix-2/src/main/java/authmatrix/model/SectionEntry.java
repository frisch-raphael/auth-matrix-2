package authmatrix.model;

import java.awt.Color;

public class SectionEntry {
    private String name;
    private final Color color;

    // Tableau 10 palette — readable, distinct
    private static final Color[] PALETTE = {
        new Color(0x4E, 0x79, 0xA7),
        new Color(0xF2, 0x8E, 0x2B),
        new Color(0xE1, 0x57, 0x59),
        new Color(0x76, 0xB7, 0xB2),
        new Color(0x59, 0xA1, 0x4F),
        new Color(0xED, 0xC9, 0x48),
        new Color(0xAF, 0x7A, 0xA1),
        new Color(0xFF, 0x9D, 0xA7),
        new Color(0x9C, 0x75, 0x5F),
        new Color(0xBA, 0xB0, 0xAC),
    };
    private static int nextColorIndex = 0;

    public SectionEntry(String name) {
        this.name = name;
        this.color = PALETTE[nextColorIndex++ % PALETTE.length];
    }

    public SectionEntry(String name, Color color) {
        this.name = name;
        this.color = color;
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public Color getColor() { return color; }

    public static void resetColorIndex() { nextColorIndex = 0; }
}
