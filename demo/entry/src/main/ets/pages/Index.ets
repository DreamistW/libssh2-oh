import demo, { DemoOptions, DemoResult } from 'libohdemo.so';

// 所有参数仅保存在当前页面内存；按钮运行完整 SSH/PTY/SFTP 演示。
@Entry
@Component
struct Index {
  @State private host: string = '';
  @State private port: string = '22';
  @State private username: string = '';
  @State private password: string = '';
  @State private fingerprint: string = '';
  @State private algorithmIndex: number = 0;
  @State private legacy: boolean = false;
  @State private running: boolean = false;
  @State private report: string = '';
  private algorithms: string[] = [
    'curve25519-sha256', 'diffie-hellman-group14-sha256', 'diffie-hellman-group16-sha512',
    'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256',
    'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1', 'diffie-hellman-group-exchange-sha1'
  ];

  // 原生报告只包含固定阶段、算法和错误码，不回显连接地址或凭据。
  private async runDemo(): Promise<void> {
    this.running = true;
    const options: DemoOptions = { host: this.host.trim(), port: Number(this.port), username: this.username,
      password: this.password, fingerprint: this.fingerprint.trim(),
      kex: this.algorithms[this.algorithmIndex], legacy: this.legacy };
    this.password = '';
    try {
      const result: DemoResult = await demo.run(options);
      this.report = (result.ok ? 'PASS' : 'FAIL ' + result.error + ' (' + result.code + ')') + '\n' +
        result.algorithm + '\n' + result.stages.join(' → ');
    } catch (error) {
      this.report = error instanceof Error ? error.message : 'Native operation failed';
    } finally { options.password = ''; this.running = false; }
  }

  build() {
    Scroll() {
      Column({ space: 12 }) {
        Text($r('app.string.title')).fontSize(28).fontWeight(FontWeight.Bold)
        TextInput({ placeholder: $r('app.string.host'), text: this.host })
          .onChange((value: string) => { this.host = value; }).enabled(!this.running)
        TextInput({ placeholder: $r('app.string.port'), text: this.port }).type(InputType.Number)
          .onChange((value: string) => { this.port = value; }).enabled(!this.running)
        TextInput({ placeholder: $r('app.string.username'), text: this.username })
          .onChange((value: string) => { this.username = value; }).enabled(!this.running)
        TextInput({ placeholder: $r('app.string.password'), text: this.password }).type(InputType.Password)
          .onChange((value: string) => { this.password = value; }).enabled(!this.running)
        TextInput({ placeholder: $r('app.string.fingerprint'), text: this.fingerprint })
          .onChange((value: string) => { this.fingerprint = value; }).enabled(!this.running)
        Select(this.algorithms.map((value: string): SelectOption => ({ value: value })))
          .selected(this.algorithmIndex).value(this.algorithms[this.algorithmIndex])
          .onSelect((index: number) => { this.algorithmIndex = index; }).enabled(!this.running)
        Row({ space: 12 }) {
          Toggle({ type: ToggleType.Switch, isOn: this.legacy })
            .onChange((value: boolean) => { this.legacy = value; }).enabled(!this.running)
          Text($r('app.string.legacy'))
        }
        Button(this.running ? $r('app.string.running') : $r('app.string.run'))
          .enabled(!this.running && this.host.length > 0 && this.username.length > 0 &&
            this.password.length > 0 && this.fingerprint.startsWith('SHA256:'))
          .onClick(() => { this.runDemo(); })
        if (this.report.length > 0) { Text(this.report).fontSize(16).width('100%') }
      }.width('100%').constraintSize({ maxWidth: 760 }).padding(28).alignItems(HorizontalAlign.Start)
    }.width('100%').height('100%').backgroundColor($r('app.color.background'))
  }
}
