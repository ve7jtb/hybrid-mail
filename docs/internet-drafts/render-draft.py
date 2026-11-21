#!/usr/bin/env python3
"""Render one RFCXML source to GitHub Markdown plus xml2rfc text and HTML.

The Markdown is a reading copy, not Internet-Draft submission text. Keeping it
generated from the same RFCXML prevents wire tables and security requirements
from drifting between the repository and the published HTML.
"""
import argparse
import calendar
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET


class Markdown:
    def __init__(self, root):
        self.root = root
        self.labels = {}
        self.links = {}
        for reference in root.findall('.//reference'):
            anchor = reference.get('anchor')
            self.labels[anchor] = anchor
            self.links[anchor] = reference.get('target', '#' + anchor)
        for container in [root.find('middle'), root.find('back')]:
            if container is not None:
                for index, section in enumerate(container.findall('section'), 1):
                    appendix = container.tag == 'back'
                    self.number(section, chr(64 + index) if appendix else str(index), appendix)

    def number(self, section, number, appendix=False):
        anchor = section.get('anchor')
        title = ''.join(section.find('name').itertext())
        label = ('Appendix ' if appendix else 'Section ') + number
        if anchor:
            self.labels[anchor] = label + ' (' + title + ')'
            self.links[anchor] = '#' + anchor
        section.set('_number', number)
        for index, child in enumerate(section.findall('section'), 1):
            self.number(child, number + '.' + str(index), appendix)

    def inline(self, node):
        text = node.text or ''
        for child in node:
            if child.tag == 'xref':
                target = child.get('target')
                if target not in self.links:
                    raise ValueError('Unresolved xref: ' + str(target))
                label = self.inline(child) or self.labels[target]
                value = '[' + label + '](' + self.links[target] + ')'
            elif child.tag == 'eref':
                target = child.get('target')
                value = '[' + (self.inline(child) or target) + '](' + target + ')'
            elif child.tag in ('tt', 'code'):
                value = '`' + self.inline(child) + '`'
            elif child.tag in ('em', 'strong'):
                mark = '*' if child.tag == 'em' else '**'
                value = mark + self.inline(child) + mark
            elif child.tag in ('bcp14', 'spanx', 'sup', 'sub'):
                value = self.inline(child)
            else:
                raise ValueError('Unsupported inline element: ' + child.tag)
            text += value + (child.tail or '')
        return re.sub(r'\s+', ' ', text).strip()

    def block(self, node, depth=2):
        if node.tag == 't':
            return self.inline(node) + '\n\n'
        if node.tag in ('artwork', 'sourcecode'):
            return '```' + (node.get('type', '') if node.tag == 'sourcecode' else 'text') + '\n' + ''.join(node.itertext()).strip('\n') + '\n```\n\n'
        if node.tag in ('ol', 'ul'):
            lines = []
            for index, item in enumerate(node.findall('li'), 1):
                prefix = str(index) + '. ' if node.tag == 'ol' else '- '
                if len(item):
                    body = ''.join(self.block(child, depth) for child in item).strip()
                else:
                    body = self.inline(item)
                lines.append(prefix + body.replace('\n', '\n   '))
            return '\n'.join(lines) + '\n\n'
        if node.tag == 'section':
            anchor = node.get('anchor')
            header = ('<a id="' + anchor + '"></a>\n\n') if anchor else ''
            header += '#' * depth + ' ' + node.get('_number', '') + ' ' + self.inline(node.find('name')) + '\n\n'
            return header + ''.join(self.block(child, depth + 1) for child in node if child.tag != 'name')
        if node.tag == 'table':
            title = node.find('name')
            output = '**' + self.inline(title) + '**\n\n' if title is not None else ''
            rows = node.findall('./thead/tr') + node.findall('./tbody/tr')
            for index, row in enumerate(rows):
                cells = [self.inline(cell).replace('|', '\\|') for cell in row]
                output += '| ' + ' | '.join(cells) + ' |\n'
                if index == 0:
                    output += '| ' + ' | '.join('---' for _ in cells) + ' |\n'
            return output + '\n'
        if node.tag == 'references':
            output = '#' * depth + ' ' + self.inline(node.find('name')) + '\n\n'
            for reference in node.findall('reference'):
                anchor = reference.get('anchor')
                front = reference.find('front')
                title = self.inline(front.find('title'))
                authors = []
                for author in front.findall('author'):
                    name = author.get('fullname') or ' '.join(filter(None, [author.get('initials'), author.get('surname')]))
                    if not name:
                        organization = author.find('organization')
                        name = self.inline(organization) if organization is not None else ''
                    if name:
                        authors.append(name)
                series = ', '.join(x.get('name', '') + ' ' + x.get('value', '') for x in reference.findall('seriesInfo'))
                date = front.find('date')
                when = ' '.join(filter(None, [date.get('month'), date.get('year')])) if date is not None else ''
                output += '<a id="' + anchor + '"></a>\n\n'
                output += '**[' + anchor + ']** ' + ', '.join(authors) + ', [' + title + '](' + self.links[anchor] + ')'
                if series:
                    output += ', ' + series
                if when:
                    output += ', ' + when
                output += '.\n\n'
                for note in reference.findall('annotation'):
                    output += self.inline(note) + '\n\n'
            return output
        raise ValueError('Unsupported block element: ' + node.tag)

    def render(self, source):
        front = self.root.find('front')
        result = '# ' + self.inline(front.find('title')) + '\n\n'
        result += '> Generated from [' + source.name + '](' + source.name + ') by `render-draft.py`. Edit RFCXML, then regenerate.\n\n'
        result += '**' + self.root.get('docName') + '** · Independent Submission · Intended status: Informational\n\n'
        date = front.find('date')
        result += 'Draft date: ' + ' '.join(filter(None, [date.get('day'), date.get('month'), date.get('year')])) + '.\n\n'
        for author in front.findall('author'):
            result += author.get('fullname', '')
            email = author.find('./address/email')
            if email is not None:
                result += ' · [' + email.text + '](mailto:' + email.text + ')'
            result += '\n\n'
        result += '## Abstract\n\n' + ''.join(self.block(child) for child in front.find('abstract'))
        for note in front.findall('note'):
            name = note.find('name')
            result += '## ' + (self.inline(name) if name is not None else note.get('title', 'Note')) + '\n\n' + ''.join(self.block(child) for child in note if child.tag != 'name')
        result += 'The authoritative formatted draft, including xml2rfc-generated boilerplate, is available as [plain text](' + source.with_suffix('.txt').name + ') and [HTML](' + source.with_suffix('.html').name + ').\n\n'
        for container in ('middle', 'back'):
            result += ''.join(self.block(child) for child in self.root.find(container))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', nargs='?', type=Path, default=Path(__file__).with_name('draft-bradley-pqmail-certificate-bundle-00.xml'))
    parser.add_argument('--xml2rfc', default='xml2rfc')
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--markdown-only', action='store_true')
    parser.add_argument('--check', action='store_true', help='Check generated Markdown without writing or running xml2rfc')
    args = parser.parse_args()
    source = args.source.resolve()
    root = ET.parse(source).getroot()
    output = Markdown(root).render(source)
    target = source.with_suffix('.md')
    if args.check:
        if not target.exists() or target.read_text() != output:
            raise SystemExit('Generated Markdown is out of date: ' + str(target))
        print('PASS Markdown matches RFCXML')
        return
    target.write_text(output)
    print('Wrote', target)
    if not args.markdown_only:
        date = root.find('front/date')
        month = list(calendar.month_name).index(date.get('month'))
        render_date = '%s-%02d-%02d' % (date.get('year'), month, int(date.get('day')))
        command = [args.xml2rfc, '--no-network', '--date', render_date, '--text', '--html', '--path', str(source.parent)]
        if args.cache:
            command += ['--cache', str(args.cache)]
        subprocess.run(command + [str(source)], check=True)


if __name__ == '__main__':
    main()
