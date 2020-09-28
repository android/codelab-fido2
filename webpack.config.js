module.exports = {
  entry: './public/components.js',
  mode: 'production',
  output: {
    filename: 'components-bundle.js',
  },
  module: {
    rules: [
      {
        test: /components\.js$/,
        loader: 'babel-loader',
        query: { presets: ['env'] },
      },
    ],
  },
};
