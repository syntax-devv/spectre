const fs = require('fs').promises;
const path = require('path');

class TemplateEngine {
  async loadTemplate(templateName) {
    try {
      const templatePath = path.join(__dirname, '..', 'templates', `${templateName}.html`);
      const template = await fs.readFile(templatePath, 'utf-8');
      return template;
    } catch (error) {
      throw new Error(`Failed to load template ${templateName}: ${error.message}`);
    }
  }

  renderTemplate(template, variables) {
    let rendered = template;
    
    for (const [key, value] of Object.entries(variables)) {
      const placeholder = `{{${key}}}`;
      rendered = rendered.split(placeholder).join(value || '');
    }
    
    return rendered;
  }

  async render(templateName, variables) {
    const template = await this.loadTemplate(templateName);
    return this.renderTemplate(template, variables);
  }
}

module.exports = new TemplateEngine();
