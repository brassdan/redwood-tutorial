import { render } from '@redwoodjs/testing/web'

import CommentForm from './CommentForm'

describe('CommentForm', () => {
  it('renders successfully', () => {
    expect(() => {
      render(<CommentForm />)
    }).not.toThrow()
  })
})
