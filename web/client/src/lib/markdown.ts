import fs from 'fs'
import path from 'path'
import { remark } from 'remark'
import html from 'remark-html'
import matter from 'gray-matter'

const contentDirectory = path.join(process.cwd(), 'content')

export async function getMarkdownContent(filename: string) {
    const fullPath = path.join(contentDirectory, filename)
    const fileContents = fs.readFileSync(fullPath, 'utf8')

    // Use gray-matter to parse the metadata section
    const { content } = matter(fileContents)

    // Use remark to convert markdown into HTML string
    const processedContent = await remark()
        .use(html, { sanitize: false })
        .process(content)

    const contentHtml = processedContent.toString()

    return contentHtml
}
