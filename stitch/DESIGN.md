---
name: ShieldSense AI Sentinel Workspace
colors:
  surface: '#f8f9ff'
  surface-dim: '#cbdbf5'
  surface-bright: '#f8f9ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#eff4ff'
  surface-container: '#e5eeff'
  surface-container-high: '#dce9ff'
  surface-container-highest: '#d3e4fe'
  on-surface: '#0b1c30'
  on-surface-variant: '#3d4a42'
  inverse-surface: '#213145'
  inverse-on-surface: '#eaf1ff'
  outline: '#6d7a72'
  outline-variant: '#bccac0'
  surface-tint: '#006c4a'
  primary: '#006948'
  on-primary: '#ffffff'
  primary-container: '#00855d'
  on-primary-container: '#f5fff7'
  inverse-primary: '#68dba9'
  secondary: '#565e74'
  on-secondary: '#ffffff'
  secondary-container: '#dae2fd'
  on-secondary-container: '#5c647a'
  tertiary: '#4648d4'
  on-tertiary: '#ffffff'
  tertiary-container: '#6063ee'
  on-tertiary-container: '#fffbff'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#85f8c4'
  primary-fixed-dim: '#68dba9'
  on-primary-fixed: '#002114'
  on-primary-fixed-variant: '#005137'
  secondary-fixed: '#dae2fd'
  secondary-fixed-dim: '#bec6e0'
  on-secondary-fixed: '#131b2e'
  on-secondary-fixed-variant: '#3f465c'
  tertiary-fixed: '#e1e0ff'
  tertiary-fixed-dim: '#c0c1ff'
  on-tertiary-fixed: '#07006c'
  on-tertiary-fixed-variant: '#2f2ebe'
  background: '#f8f9ff'
  on-background: '#0b1c30'
  surface-variant: '#d3e4fe'
typography:
  headline-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-lg-mobile:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  label-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.05em
  technical-code:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  technical-data:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  base: 4px
  xs: 0.25rem
  sm: 0.5rem
  md: 1rem
  lg: 1.5rem
  xl: 2rem
  container-max: 1440px
  gutter: 24px
---

## Brand & Style

The design system is engineered for high-stakes security environments where clarity, precision, and calm are paramount. The brand personality is that of a "Silent Sentinel"—vigilant and powerful, yet unobtrusive and professional. 

The aesthetic follows a **Corporate Modern** approach with a focus on high information density delivered through an airy, breathable interface. It leverages extreme cleanliness, subtle borders, and intentional whitespace to reduce cognitive load during critical monitoring tasks. The visual language conveys trust through stability (grid-alignment) and precision (monospaced accents).

## Colors

The palette is anchored by a calming Emerald Green primary accent, symbolizing safety and "system go" status. 

- **Primary (#059669):** Used for primary actions, success states, and active security indicators.
- **Secondary (#0f172a):** A deep Navy used for high-contrast text and sidebar navigation backgrounds to ground the UI.
- **Neutral/Surface:** The background uses a cool Slate-50 (#f8fafc) to provide a soft canvas for pure white cards, creating a subtle layering effect without heavy shadows.
- **Borders (#e2e8f0):** Used rigorously to define structure in a flat environment.

## Typography

This design system utilizes a dual-font strategy to distinguish between human-centric interface elements and machine-generated data.

- **Inter:** The primary typeface for all UI controls, navigation, and prose. It provides a neutral, highly legible foundation.
- **JetBrains Mono:** Reserved exclusively for technical strings, IP addresses, hashes, logs, and terminal outputs. Its monospaced nature signals "hard data" to the user.

Headlines should use tighter letter spacing to maintain a compact, professional appearance. Labels are frequently set in Uppercase when used for small metadata tags to increase scannability.

## Layout & Spacing

The layout utilizes a **Fixed Grid** philosophy for the main workspace to ensure predictable data visualization. 

- **Desktop (1440px+):** 12-column grid, 24px gutters, 40px side margins.
- **Tablet (768px - 1439px):** 8-column grid, 16px gutters, 24px side margins.
- **Mobile (<767px):** 4-column grid, 16px gutters, 16px side margins.

A strict 4px baseline grid governs all internal component spacing (padding/margins). Components should prioritize vertical rhythm to handle long lists of security events.

## Elevation & Depth

This design system avoids heavy shadows to maintain a clean, "Aero" aesthetic. Depth is communicated primarily through **Tonal Layers** and **Low-Contrast Outlines**.

- **Level 0 (Background):** #f8fafc (The foundation).
- **Level 1 (Cards/Surface):** #ffffff with a 1px border (#e2e8f0). No shadow.
- **Level 2 (Popovers/Modals):** #ffffff with a 1px border (#e2e8f0) and a very soft, diffused ambient shadow (0px 10px 15px -3px rgba(0,0,0,0.05)).

Active states and focus rings use a 2px offset with the Primary Emerald color to ensure accessibility without cluttering the canvas.

## Shapes

The shape language is **Soft (0.25rem)**. This provides just enough curvature to feel modern and approachable while maintaining the structural integrity and "seriousness" of a technical tool. 

- **Standard Elements:** 4px radius (Buttons, Input fields, Checkboxes).
- **Containers:** 8px radius (Cards, Modals).
- **Interactive Feedback:** Hover states should mirror the underlying component's radius exactly.

## Components

### Buttons
- **Primary:** Solid #059669 background with white text. 4px radius.
- **Secondary:** White background with #e2e8f0 border and #0f172a text.
- **Ghost:** Transparent background, #64748b text. Used for less frequent actions.

### Technical Data Tables
Tables are the heart of this workspace. Use `technical-data` (JetBrains Mono) for all cell values. Headers use `label-sm` (Inter) in all-caps. Rows should have a subtle #f8fafc hover state.

### Input Fields
Inputs use #ffffff backgrounds with #e2e8f0 borders. On focus, the border transitions to #059669 with a subtle 2px outer glow of the same color at 10% opacity.

### Security Status Chips
- **Secure:** Emerald Green text on 10% Emerald background.
- **Warning:** Amber-500 text on 10% Amber background.
- **Critical:** Red-600 text on 10% Red background.
- All chips are 24px height with a 4px radius (not pill-shaped) to match the system's geometric rigor.

### Dashboard Cards
Cards must include a 1px #e2e8f0 border. Card headers should be separated by a 1px horizontal divider to clearly demarcate the title and controls from the content.