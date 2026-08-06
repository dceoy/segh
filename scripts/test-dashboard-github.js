"use strict";

class GitHub {
  constructor() {
    this.labels = []; this.issues = []; this.comments = []; this.next = 1;
    this.failCreate = false; this.failComment = false;
    this.rest = {issues: {
      listLabelsForRepo: async () => ({data: this.labels}),
      createLabel: async ({name}) => ({data: this.labels[this.labels.push({name}) - 1]}),
      listForRepo: async () => ({data: this.issues}),
      listComments: async ({issue_number}) => ({data: this.comments.filter((item) => item.issue_number === issue_number)}),
      create: async (params) => {
        const issue = {number: this.next++, title: params.title, body: params.body, state: "open", labels: params.labels.map((name) => ({name}))};
        this.issues.push(issue);
        if (this.failCreate) { this.failCreate = false; const error = new Error("ambiguous create"); error.status = 502; throw error; }
        return {data: issue};
      },
      update: async (params) => {
        const issue = this.issues.find((item) => item.number === params.issue_number);
        for (const key of ["title", "body", "state"]) if (params[key] !== undefined) issue[key] = params[key];
        if (params.labels) issue.labels = params.labels.map((name) => ({name}));
        return {data: issue};
      },
      createComment: async (params) => {
        const item = {id: this.comments.length + 1, ...params}; this.comments.push(item);
        if (this.failComment) { this.failComment = false; const error = new Error("ambiguous comment"); error.status = 502; throw error; }
        return {data: item};
      },
    }};
  }
}

module.exports = {GitHub};
